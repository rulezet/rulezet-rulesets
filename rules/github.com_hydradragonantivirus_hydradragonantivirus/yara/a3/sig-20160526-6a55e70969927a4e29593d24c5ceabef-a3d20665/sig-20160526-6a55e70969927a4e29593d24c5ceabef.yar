rule sig_20160526_6a55e70969927a4e29593d24c5ceabef {
  meta:
    description = "datamaliciousorder - file 20160526_6a55e70969927a4e29593d24c5ceabef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5d0910329b7ef7ab2ef4854e08af14cb5488fcef32d61f495c5b24be2ab23a2"

  strings:
    $s1  = "function BxEgdMea(JQWTLtqFOjIrA) {var mMzbsFvOgs = bbozBHRTAWbkcPy.join(bWjzGgJYCOrPdUMybsY[0]);var LBwrDHvgrKjGKjpxJMAlJNxT, CJ" ascii
    $s2  = "5), 2) - 1))-496)) CjHgk += TWyKnawQT(LBwrDHvgrKjGKjpxJMAlJNxT, CJllMusdqv);else CjHgk += MOtKqHboub(LBwrDHvgrKjGKjpxJMAlJNxT, C" ascii
    $s3  = ") CjHgk += R(LBwrDHvgrKjGKjpxJMAlJNxT);else if (aiJquleA == (560 + Math.round((Math.pow(Math.sin(985), 2) + Math.pow(Math.cos(98" ascii
    $s4  = "function kJNXuhQYGNl(xGhjso,XDZjYs){return xGhjso.charAt(XDZjYs);}" fullword ascii
    $s5  = "function BxEgdMea(JQWTLtqFOjIrA) {var mMzbsFvOgs = bbozBHRTAWbkcPy.join(bWjzGgJYCOrPdUMybsY[0]);var LBwrDHvgrKjGKjpxJMAlJNxT, CJ" ascii
    $s6  = "function MOtKqHboub(xzNSGPso,rHqPpOLJq,rNnmOSAJxLhBXnBbjE){return String.fromCharCode(xzNSGPso,rHqPpOLJq,rNnmOSAJxLhBXnBbjE);}" fullword ascii
    $s7  = "function R(RtDuVrPHThFxxBWOajMM){return String.fromCharCode(RtDuVrPHThFxxBWOajMM);}" fullword ascii
    $s8  = "function TWyKnawQT(BlBsUFJlkwNqc,lMJLRK){return String.fromCharCode(BlBsUFJlkwNqc,lMJLRK);}" fullword ascii
    $s9  = "JllMusdqv, RBYpoWnVooouXJgbYD);} while (gGnaPLIrxxUKlBv < JQWTLtqFOjIrA.length);return CjHgk;}" fullword ascii
    $s10 = "function ANCmkzDsxzTczFMtqkGhq(WgvHzfedonbFaPYspPE,mlfirPKrOc){return WgvHzfedonbFaPYspPE.indexOf(mlfirPKrOc);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}