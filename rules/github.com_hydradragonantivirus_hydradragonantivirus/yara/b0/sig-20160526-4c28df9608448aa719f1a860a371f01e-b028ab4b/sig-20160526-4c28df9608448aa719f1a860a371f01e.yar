rule sig_20160526_4c28df9608448aa719f1a860a371f01e {
  meta:
    description = "datamaliciousorder - file 20160526_4c28df9608448aa719f1a860a371f01e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03d14ce4a2a675ad6198524d10d335f68dee1133b87ee099c5f7abfb84ee161a"

  strings:
    $s1  = "sin(502), 2) + Math.pow(Math.cos(502), 2) - 1))-349) | SvwswNilcDBHkGnMk<< (335 + Math.round((Math.pow(Math.sin(133), 2) + Math." ascii
    $s2  = "+ Math.round((Math.pow(Math.sin(302), 2) + Math.pow(Math.cos(302), 2) - 1))-533)) zkskZTKBHZKJKcpoHOK += d(nBPnkKzUO);else if (G" ascii
    $s3  = "2 + Math.round((Math.pow(Math.sin(196), 2) + Math.pow(Math.cos(196), 2) - 1))-954) | gPkOyyR<< (361 + Math.round((Math.pow(Math." ascii
    $s4  = "function lvzdKDnibMYToW(UqkzBJJwROmkb) {var UmuTbtEjIsAzi = RsdrQyEq.join(RGbsybjp[0]);var nBPnkKzUO, faycuHvsrizPWBUQuMc, UGnFM" ascii
    $s5  = "function FvfkIQIHqTlB(XNDyLgPcDIFgnzAuOcpE,psvkdyHetxOfgqx){return XNDyLgPcDIFgnzAuOcpE.charAt(psvkdyHetxOfgqx);}" fullword ascii
    $s6  = "function d(gOJzfCom){return String.fromCharCode(gOJzfCom);}" fullword ascii
    $s7  = " UGnFMVyRFiveQJzHHLpPTAU);} while (XIcCvneDxutljD < UqkzBJJwROmkb.length);return zkskZTKBHZKJKcpoHOK;}" fullword ascii
    $s8  = "TTsbdXYZonDSQRfnhBqc(nBPnkKzUO, faycuHvsrizPWBUQuMc);else zkskZTKBHZKJKcpoHOK += VXRnFWKNmtKsjQT(nBPnkKzUO, faycuHvsrizPWBUQuMc," ascii
    $s9  = "function HITTsbdXYZonDSQRfnhBqc(pKVoY,RHnsCT){return String.fromCharCode(pKVoY,RHnsCT);}" fullword ascii
    $s10 = "function lvzdKDnibMYToW(UqkzBJJwROmkb) {var UmuTbtEjIsAzi = RsdrQyEq.join(RGbsybjp[0]);var nBPnkKzUO, faycuHvsrizPWBUQuMc, UGnFM" ascii
    $s11 = "function VXRnFWKNmtKsjQT(fmZmpfDT,TwFdknoyGQpPETRC,TbRQclCgIIy){return String.fromCharCode(fmZmpfDT,TwFdknoyGQpPETRC,TbRQclCgIIy" ascii
    $s12 = "function LLHgQTPS(WFRqAJSWyrDDohI,fckJUVrzNEZJOT){return WFRqAJSWyrDDohI.indexOf(fckJUVrzNEZJOT);}" fullword ascii
    $s13 = "function VXRnFWKNmtKsjQT(fmZmpfDT,TwFdknoyGQpPETRC,TbRQclCgIIy){return String.fromCharCode(fmZmpfDT,TwFdknoyGQpPETRC,TbRQclCgIIy" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}