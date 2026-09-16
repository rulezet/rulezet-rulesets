rule sig_20160526_4641b6168cc64abc02023f56c671802e {
  meta:
    description = "datamaliciousorder - file 20160526_4641b6168cc64abc02023f56c671802e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dffb71e018b5f54fc960c2de92b26e2fee423a4d4a19a1ac6ffaf644e80d21c3"

  strings:
    $s1  = "function jZwDsX(nbrrpycwzbCCB) {var ktrdYgyGWcMHfQYXfwY = OYwcVGbDa.join(XWFwPDtXsQkXxiFlynOFlHN[0]);var GHLSJE, wKqHQrotcOrvMKv" ascii
    $s2  = "round((Math.pow(Math.sin(930), 2) + Math.pow(Math.cos(930), 2) - 1))-816) | ELuKGDZmNiehFwURCRiDDR<< (284 + Math.round((Math.pow" ascii
    $s3  = "CRiDDR == (870 + Math.round((Math.pow(Math.sin(516), 2) + Math.pow(Math.cos(516), 2) - 1))-806)) TQGsw += tf(GHLSJE);else if (DH" ascii
    $s4  = "< (523 + Math.round((Math.pow(Math.sin(778), 2) + Math.pow(Math.cos(778), 2) - 1))-505) | dUaMEDDZAzSwTzCyMBkjaYE<< (828 + Math." ascii
    $s5  = "function xgkvExjCbXKgeTdXvnwUf(mTnXFMBWKBqmcjiuw,ysKsboVEyGJdR){return mTnXFMBWKBqmcjiuw.indexOf(ysKsboVEyGJdR);}" fullword ascii
    $s6  = "function cNKhnETwaIuzmAckS(lqYAaNMesEMWNHhkjRcKKPxm,YGUsmXBweIUvFQJnHOYksFzU){return lqYAaNMesEMWNHhkjRcKKPxm.charAt(YGUsmXBweIU" ascii
    $s7  = "function cNKhnETwaIuzmAckS(lqYAaNMesEMWNHhkjRcKKPxm,YGUsmXBweIUvFQJnHOYksFzU){return lqYAaNMesEMWNHhkjRcKKPxm.charAt(YGUsmXBweIU" ascii
    $s8  = "rpycwzbCCB.length);return TQGsw;}" fullword ascii
    $s9  = "function jZwDsX(nbrrpycwzbCCB) {var ktrdYgyGWcMHfQYXfwY = OYwcVGbDa.join(XWFwPDtXsQkXxiFlynOFlHN[0]);var GHLSJE, wKqHQrotcOrvMKv" ascii
    $s10 = "function xVTFPmHJtXPPHQu(vZkkmpe,bPaUVazstQDN){return String.fromCharCode(vZkkmpe,bPaUVazstQDN);}" fullword ascii
    $s11 = "function VRQiXzhgH(zuFVMnwsnNHyNfjFxDur,dpZPMxBoSKcxbjmvb,rnCdFPnNYwo){return String.fromCharCode(zuFVMnwsnNHyNfjFxDur,dpZPMxBoS" ascii
    $s12 = "PPHQu(GHLSJE, wKqHQrotcOrvMKvMgSNhSTi);else TQGsw += VRQiXzhgH(GHLSJE, wKqHQrotcOrvMKvMgSNhSTi, kypRloam);} while (PbBsGSA < nbr" ascii
    $s13 = "function tf(hTryGmArBhaQRpPYtzYraFBg){return String.fromCharCode(hTryGmArBhaQRpPYtzYraFBg);}" fullword ascii
    $s14 = "function VRQiXzhgH(zuFVMnwsnNHyNfjFxDur,dpZPMxBoSKcxbjmvb,rnCdFPnNYwo){return String.fromCharCode(zuFVMnwsnNHyNfjFxDur,dpZPMxBoS" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}