rule sig_20160526_145ce1d4258d23d3d5b68c797e084a6c {
  meta:
    description = "datamaliciousorder - file 20160526_145ce1d4258d23d3d5b68c797e084a6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "907404f53a681424d4dfc195c340da7157eba8a8563d658c0f847a1d01e42612"

  strings:
    $s1  = "function jcKoPFIvvVf(JOnujpFGCVrXv) {var omdJUTbLSuHYnTEQoonf = KyQeFnRI.join(FnZFBAACvTHOISmPi[0]);var AXVxQ, FRVDjThfvBnPOXoyd" ascii
    $s2  = "xQ);else if (hpPNQiaoXLnJwpyw == (272 + Math.round((Math.pow(Math.sin(332), 2) + Math.pow(Math.cos(332), 2) - 1))-208)) OVgJQdZa" ascii
    $s3  = "function HnKUplHkCzWMHGKpCYToB(bmABJUcSp,JtCkyJMkrNmdDnaYcK){return bmABJUcSp.charAt(JtCkyJMkrNmdDnaYcK);}" fullword ascii
    $s4  = "function ZhKsxgtEIhvMuRN(zkceEKSTAWkWkJjSAnUnxvbR,bMybuyOgnSFIPxyV,uetAPqIsUFdduUNLREuNUP){return String.fromCharCode(zkceEKSTAW" ascii
    $s5  = "dbMrQRztKRO += pNUAJkxxDxwPJU(AXVxQ, FRVDjThfvBnPOXoyd);else OVgJQdZadbMrQRztKRO += ZhKsxgtEIhvMuRN(AXVxQ, FRVDjThfvBnPOXoyd, vj" ascii
    $s6  = "EkJQKULHM);} while (JYDvo < JOnujpFGCVrXv.length);return OVgJQdZadbMrQRztKRO;}" fullword ascii
    $s7  = "function pNUAJkxxDxwPJU(Rpxdijp,EEBdpATNsrRayGmZ){return String.fromCharCode(Rpxdijp,EEBdpATNsrRayGmZ);}" fullword ascii
    $s8  = "function cKfYSaeWtROzgUMolMJgK(ttQHYIgtSJDtJMlXSRYW,vVFkqcyZfrxEYS){return ttQHYIgtSJDtJMlXSRYW.indexOf(vVFkqcyZfrxEYS);}" fullword ascii
    $s9  = "function ZhKsxgtEIhvMuRN(zkceEKSTAWkWkJjSAnUnxvbR,bMybuyOgnSFIPxyV,uetAPqIsUFdduUNLREuNUP){return String.fromCharCode(zkceEKSTAW" ascii
    $s10 = "function jcKoPFIvvVf(JOnujpFGCVrXv) {var omdJUTbLSuHYnTEQoonf = KyQeFnRI.join(FnZFBAACvTHOISmPi[0]);var AXVxQ, FRVDjThfvBnPOXoyd" ascii
    $s11 = "function Vc(DEQTBRbdHtJlxecrY){return String.fromCharCode(DEQTBRbdHtJlxecrY);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}