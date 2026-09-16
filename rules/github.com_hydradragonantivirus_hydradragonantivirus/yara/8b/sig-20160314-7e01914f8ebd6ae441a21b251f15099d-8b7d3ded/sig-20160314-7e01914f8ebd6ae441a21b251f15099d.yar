rule sig_20160314_7e01914f8ebd6ae441a21b251f15099d {
  meta:
    description = "datamaliciousorder - file 20160314_7e01914f8ebd6ae441a21b251f15099d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96329f951a5ed631900c3f8a6c42719f96df4f239aad798ace90d98b2ee47c48"

  strings:
    $s1 = "pFgEefmvpzm.open(bzmEVVM, SWGKodnSXEi + rmlTJAwnDRYNWN + SutvdVa + vKHqCFo + RLjHlhpUgUPSQc + keKdnFNwCTZsV + OrmXVIxH + LJwPX +" ascii
    $s2 = "while (pFgEefmvpzm.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return KmWEuPmcDP + fpWGGQ + hXPu + UaHPepmDnviGEJ + nrzFYVsTUINFh + tRFk + oepOHozHDi + vvChsteFxuNyBBC" fullword ascii
    $s4 = "dkK + QXfyXNQTqsMf + nbxAkUGeJmbckp + vAQSGLyPdlXniBV + wSc + yHNawPeXIBvClJ + kZjgZ + dtFFc, false);" fullword ascii
    $s5 = "function pMu(n)" fullword ascii
    $s6 = "var aeVm = new Date();" fullword ascii
    $s7 = "function QkZrNHcAw(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}