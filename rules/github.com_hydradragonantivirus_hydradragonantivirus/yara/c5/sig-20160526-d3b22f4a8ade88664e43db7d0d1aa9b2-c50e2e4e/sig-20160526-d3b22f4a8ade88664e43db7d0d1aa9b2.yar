rule sig_20160526_d3b22f4a8ade88664e43db7d0d1aa9b2 {
  meta:
    description = "datamaliciousorder - file 20160526_d3b22f4a8ade88664e43db7d0d1aa9b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b48d90c4e7b9d3912c92714b83dc62bc6c6117b729a0bf6b31131d8023597ea8"

  strings:
    $s1  = "function SuAwpnnEIw(KqhBRedEbRKqN) {var SZtOSKc = QpZploGSS.join(ZoIhjUIYhxcDORMBqLZfaH[0]);var uzJvHzgAHfBAAnR, DqFRiJskfAiRswO" ascii
    $s2  = ") - 1))-226)) ECEpYMv += eAnIS(uzJvHzgAHfBAAnR, DqFRiJskfAiRswOhJFNKEA);else ECEpYMv += sfejTqCoBiHqgToe(uzJvHzgAHfBAAnR, DqFRiJ" ascii
    $s3  = "CEpYMv += kB(uzJvHzgAHfBAAnR);else if (ejwVUurwapXJ == (290 + Math.round((Math.pow(Math.sin(202), 2) + Math.pow(Math.cos(202), 2" ascii
    $s4  = "function YvwjIxZRzXYVhdJFaiwG(rBtipTSsXe,whEUoaAvPCBiJcLAGIVE){return rBtipTSsXe.charAt(whEUoaAvPCBiJcLAGIVE);}" fullword ascii
    $s5  = "function SuAwpnnEIw(KqhBRedEbRKqN) {var SZtOSKc = QpZploGSS.join(ZoIhjUIYhxcDORMBqLZfaH[0]);var uzJvHzgAHfBAAnR, DqFRiJskfAiRswO" ascii
    $s6  = "function sfejTqCoBiHqgToe(onNrgsiMo,FiLCMQGRx,tmMNAfijx){return String.fromCharCode(onNrgsiMo,FiLCMQGRx,tmMNAfijx);}" fullword ascii
    $s7  = "function kB(BqaRGnJGcUWuKPFCIXVosSX){return String.fromCharCode(BqaRGnJGcUWuKPFCIXVosSX);}" fullword ascii
    $s8  = "function EyUkZzXuvdGHmbv(NLmbbFnwEaWAfUoSom,rrwHViBPvRFCjDE){return NLmbbFnwEaWAfUoSom.indexOf(rrwHViBPvRFCjDE);}" fullword ascii
    $s9  = "function eAnIS(nRMOUhPnRKw,MErPROPYzlEkIctcKD){return String.fromCharCode(nRMOUhPnRKw,MErPROPYzlEkIctcKD);}" fullword ascii
    $s10 = "skfAiRswOhJFNKEA, OXnBhCJneYPPATq);} while (oIwIfliIYaigNZcziPEj < KqhBRedEbRKqN.length);return ECEpYMv;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}