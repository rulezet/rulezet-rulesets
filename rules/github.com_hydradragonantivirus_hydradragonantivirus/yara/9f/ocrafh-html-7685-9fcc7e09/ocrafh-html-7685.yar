import "pe"
rule ocrafh_html_7685 {
  meta:
    description = "Files - file ocrafh.html.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2022-02-01"
    hash1       = "956ecb4afa437eafe56f958b34b6a78303ad626baee004715dc6634b7546bf85"

  strings:
    $s1  = "Over.dll" fullword wide
    $s2  = "c:\\339\\Soon_Back\\Hope\\Wing\\Subject-sentence\\Over.pdb" fullword ascii
    $s3  = "7766333344" ascii  
    $s4  = "6655557744" ascii  
    $s5  = "7733225566" ascii  
    $s6  = "5577445500" ascii  
    $s7  = "113333" ascii  
    $s8  = "'56666" fullword ascii  
    $s9  = "224444" ascii  
    $s10 = "0044--" fullword ascii  
    $s11 = "444455" ascii  
    $s12 = "5555//" fullword ascii  
    $s13 = "44...." fullword ascii  
    $s14 = ",,,2255//5566" fullword ascii  
    $s15 = "44//446644//" fullword ascii  
    $s16 = "7755//44----." fullword ascii  
    $s17 = "?^.4444--,,55" fullword ascii  
    $s18 = "66,,5566////55" fullword ascii  
    $s19 = "operator co_await" fullword ascii
    $s20 = "?\"55//////77" fullword ascii  

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "fadf54554241c990b4607d042e11e465" and (pe.exports("Dropleave") and pe.exports("GlassExercise") and pe.exports("Mehope") and pe.exports("Top")) or 8 of them)
}