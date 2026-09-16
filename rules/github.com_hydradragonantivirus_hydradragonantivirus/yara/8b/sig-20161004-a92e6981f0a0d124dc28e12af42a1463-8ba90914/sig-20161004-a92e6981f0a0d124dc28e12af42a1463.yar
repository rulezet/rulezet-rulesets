rule sig_20161004_a92e6981f0a0d124dc28e12af42a1463 {
  meta:
    description = "datamaliciousorder - file 20161004_a92e6981f0a0d124dc28e12af42a1463.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fef7b08487bac1bdda88206e22ebc4390fa543367fb967c3b85c1491aaab3443"

  strings:
    $s1  = "return (new Function(\"d1\",\"var fd=d1.m\"+f5()+\"tch(/\\\\S{\"+\"\"+\"4}/\"+f5()+\"),fb=\\\"\\\",c2=0\"+\"\"+\";whil\"+f5()+\"" ascii
    $s2  = "+\"String.fromCha\"+\"\"+\"rCod\"+f5()+\"(parseInt(fd[c2].sub\"+f5()+\"tr(2,2),16)^72);c2+\"+f5()+\";}return ev\"+f5()+\"\"+\"\"" ascii
    $s3  = "function bb(f3)" fullword ascii
    $s4  = "function f5()" fullword ascii
    $s5  = "while(a1<1)" fullword ascii
    $s6  = "return (new Function(\"d1\",\"var fd=d1.m\"+f5()+\"tch(/\\\\S{\"+\"\"+\"4}/\"+f5()+\"),fb=\\\"\\\",c2=0\"+\"\"+\";whil\"+f5()+\"" ascii
    $s7  = "function d_(c3)" fullword ascii
    $s8  = "var c1=new Array(\"a\",\"e\",\"s\",\"+\",\"g\");" fullword ascii
    $s9  = "return c1[Math.floor(Math.random()*c1.length)];" fullword ascii
    $s10 = "catch(_8)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}