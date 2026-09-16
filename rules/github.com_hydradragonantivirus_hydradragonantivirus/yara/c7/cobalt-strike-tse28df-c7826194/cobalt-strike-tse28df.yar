import "pe"
rule cobalt_strike_TSE28DF {
  meta:
    description = "exe - file TSE28DF.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-01-05"
    hash1       = "65282e01d57bbc75f24629be9de126f2033957bd8fe2f16ca2a12d9b30220b47"

  strings:
    $s1  = "mneploho86.dll" fullword ascii
    $s2  = "C:\\projects\\Project1\\Project1.pdb" fullword ascii
    $s3  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s4  = "AppPolicyGetThreadInitializationType" fullword ascii
    $s5  = "boltostrashno.nfo" fullword ascii
    $s6  = "operator<=>" fullword ascii
    $s7  = "operator co_await" fullword ascii
    $s8  = ".data$rs" fullword ascii
    $s9  = "tutoyola" fullword ascii
    $s10 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
    $s11 = "vector too long" fullword ascii
    $s12 = "wrong protocol type" fullword ascii  
    $s13 = "network reset" fullword ascii  
    $s14 = "owner dead" fullword ascii  
    $s15 = "connection already in progress" fullword ascii  
    $s16 = "network down" fullword ascii  
    $s17 = "protocol not supported" fullword ascii  
    $s18 = "connection aborted" fullword ascii  
    $s19 = "network unreachable" fullword ascii  
    $s20 = "host unreachable" fullword ascii  

  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and
    (pe.imphash() == "ab74ed3f154e02cfafb900acffdabf9e" or all of them)
}