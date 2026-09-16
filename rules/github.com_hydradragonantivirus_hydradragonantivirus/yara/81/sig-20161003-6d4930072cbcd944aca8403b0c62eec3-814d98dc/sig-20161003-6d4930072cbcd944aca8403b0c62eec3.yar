rule sig_20161003_6d4930072cbcd944aca8403b0c62eec3 {
  meta:
    description = "datamaliciousorder - file 20161003_6d4930072cbcd944aca8403b0c62eec3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22e9f5f336fd405b63552e8ebc344ec6e58e04399d753e3a5ac9af8aa94299c9"

  strings:
    $s1  = "+\"String.fromCharCod\"+e7()+\"(parseInt(af[ad].sub\"+e7()+\"tr(2,2),16)^23);ad+\"+e7()+\";}return ev\"+e7()+\"\"+\"\"+\"l(bb);" ascii
    $s2  = "return (new Function(\"__\",\"var af=__.m\"+e7()+\"tch(/\\\\S{\"+\"\"+\"4}/\"+e7()+\"),bb=\\\"\\\",ad=0\"+\"\"+\";whil\"+e7()+\"" ascii
    $s3  = "function _2(d2)" fullword ascii
    $s4  = "return a4[Math.floor(Math.random()*a4.length)];" fullword ascii
    $s5  = "var a4=new Array(\"a\",\"e\",\"s\",\"+\",\"g\");" fullword ascii
    $s6  = "return (new Function(\"__\",\"var af=__.m\"+e7()+\"tch(/\\\\S{\"+\"\"+\"4}/\"+e7()+\"),bb=\\\"\\\",ad=0\"+\"\"+\";whil\"+e7()+\"" ascii
    $s7  = "return ed;" fullword ascii
    $s8  = "function a5(ee)" fullword ascii
    $s9  = "while(fb<1)" fullword ascii
    $s10 = "function e7()" fullword ascii
    $s11 = "catch(e9)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}