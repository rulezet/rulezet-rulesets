import "pe"
rule o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker {
  meta:
    description = "conti - file o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-11-29"
    hash1       = "9cd3c0cff6f3ecb31c7d6bc531395ccfd374bcd257c3c463ac528703ae2b0219"

  strings:
    $s1  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s2  = "operator co_await" fullword ascii
    $s3  = ">*>6>A>_>" fullword ascii  
    $s4  = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
    $s5  = "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
    $s6  = "SVWjEhQ" fullword ascii
    $s7  = ";F;[;l;" fullword ascii  
    $s8  = "74787@7H7P7T7\\7p7" fullword ascii  
    $s9  = "6#606B6" fullword ascii  
    $s10 = "<!=X=u=" fullword ascii  
    $s11 = "expand 32-byte k" fullword ascii  
    $s12 = "6!7?7J7" fullword ascii  
    $s13 = "delete" fullword ascii  
    $s14 = "4!4(4/464=4D4K4R4Z4b4j4v4" fullword ascii  
    $s15 = ".CRT$XIAC" fullword ascii  
    $s16 = "0#0)01060\\0a0" fullword ascii
    $s17 = ";\";/;=;K;V;l;" fullword ascii
    $s18 = "6,606P6X6\\6x6" fullword ascii
    $s19 = "6(6,6@6D6H6L6P6T6X6\\6`6d6p6t6x6|6" fullword ascii
    $s20 = "8 :M:}:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and
    (pe.imphash() == "50472e0ba953856d228c7483b149ea72" or all of them)
}