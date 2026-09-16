rule sig_20160526_35b7bccdcd41023e7dd5994da0432f6d {
  meta:
    description = "datamaliciousorder - file 20160526_35b7bccdcd41023e7dd5994da0432f6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9481d998a50cfb4a010fc40de46fd56aa8386f20d258a630af07262e1a20eb81"

  strings:
    $s1  = "function jGiQNiPZRWTb(xLKkoLRnfxDIW) {var arykApTFUrLexZ = TaKgBSWJTPplqEHMlOoGB.join(JueglSgWeipsntOPLArfhSv[0]);var xKkCpgOJGD" ascii
    $s2  = "(Math.sin(505), 2) + Math.pow(Math.cos(505), 2) - 1))-390) & 0xff;CBftLdxZ = fgsSyLGSqEwMApgHlOOWNUqi>> (967 + Math.round((Math." ascii
    $s3  = "gOJGDDEakZgZ);else if (qZAydXzJpIsnbxoIKJXfWrTY == (1060 + Math.round((Math.pow(Math.sin(631), 2) + Math.pow(Math.cos(631), 2) -" ascii
    $s4  = "function OjvBiDHlxhBXqDHeV(iimrV,hOxUdcCfPg){return iimrV.charAt(hOxUdcCfPg);}" fullword ascii
    $s5  = "function jGiQNiPZRWTb(xLKkoLRnfxDIW) {var arykApTFUrLexZ = TaKgBSWJTPplqEHMlOoGB.join(JueglSgWeipsntOPLArfhSv[0]);var xKkCpgOJGD" ascii
    $s6  = " 1))-996)) PpVFZsKjgf += ExTEbkSSzbfffDSTWDYDFchv(xKkCpgOJGDDEakZgZ, CBftLdxZ);else PpVFZsKjgf += zfMtzkAhVLQctNrwiXnZqfRh(xKkCp" ascii
    $s7  = "gOJGDDEakZgZ, CBftLdxZ, uWTCwOqwqSePErTcJgLELfj);} while (upwiqEpMGp < xLKkoLRnfxDIW.length);return PpVFZsKjgf;}" fullword ascii
    $s8  = "function ExTEbkSSzbfffDSTWDYDFchv(AmKEOwVjlkpxv,nvOQcNCxOpQkKYzDFOMd){return String.fromCharCode(AmKEOwVjlkpxv,nvOQcNCxOpQkKYzDF" ascii
    $s9  = "function s(mWUokgQAUkwvmkTqaW){return String.fromCharCode(mWUokgQAUkwvmkTqaW);}" fullword ascii
    $s10 = "function IJpBXMuEhxMJEhPJP(srwmLPloyPjohqHBpRj,ZgRkHWBfXGhOIdhDMR){return srwmLPloyPjohqHBpRj.indexOf(ZgRkHWBfXGhOIdhDMR);}" fullword ascii
    $s11 = "function zfMtzkAhVLQctNrwiXnZqfRh(aiRplGMRlFXA,YZqrzcEfUUvZCJInKcL,jCRITnhM){return String.fromCharCode(aiRplGMRlFXA,YZqrzcEfUUv" ascii
    $s12 = "function zfMtzkAhVLQctNrwiXnZqfRh(aiRplGMRlFXA,YZqrzcEfUUvZCJInKcL,jCRITnhM){return String.fromCharCode(aiRplGMRlFXA,YZqrzcEfUUv" ascii
    $s13 = "function ExTEbkSSzbfffDSTWDYDFchv(AmKEOwVjlkpxv,nvOQcNCxOpQkKYzDFOMd){return String.fromCharCode(AmKEOwVjlkpxv,nvOQcNCxOpQkKYzDF" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}