rule sig_20160924_4be60e3e56cb55559bba1f9b1543264c {
  meta:
    description = "datamaliciousorder - file 20160924_4be60e3e56cb55559bba1f9b1543264c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21cf958cdea5ae1cb6b54f277599b7ec3c745ebb534dc7136f93f82d518fceca"

  strings:
    $s1  = "return new Array('af','.sub'+''+'str(2,2),1','ee','ee','ee')[Math.floor(Math.random()*5)];" fullword ascii
    $s2  = "function d9()" fullword ascii
    $s3  = "function ed()" fullword ascii
    $s4  = "return new Array('af','arC'+''+'ode(parseIn','ee','a8')[Math.floor(Math.random()*4)];" fullword ascii
    $s5  = "while(bd<1)" fullword ascii
    $s6  = "function f3()" fullword ascii
    $s7  = "return(new Function(a0)());" fullword ascii
    $s8  = "return (new Function('c3',''+f3()+''+'u'+''+'rn'+''+' Str'+''+'ing'+''+'.fr'+''+'omCh'+d9()+'t(c3'+ed()+'6)^82)')(a3));" fullword ascii
    $s9  = "function d5(a3)" fullword ascii
    $s10 = "function e9(da)" fullword ascii
    $s11 = "return b9;" fullword ascii
    $s12 = "while(fc<f5.length)" fullword ascii
    $s13 = "return new Array('af','r'+''+'et','ee','a8')[Math.floor(Math.random()*4)];" fullword ascii
    $s14 = "function ef(a0)" fullword ascii
    $s15 = "catch(db)" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}