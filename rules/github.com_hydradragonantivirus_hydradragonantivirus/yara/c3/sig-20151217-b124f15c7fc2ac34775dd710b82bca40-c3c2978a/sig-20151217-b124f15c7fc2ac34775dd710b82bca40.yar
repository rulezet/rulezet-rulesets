rule sig_20151217_b124f15c7fc2ac34775dd710b82bca40 {
  meta:
    description = "datamaliciousorder - file 20151217_b124f15c7fc2ac34775dd710b82bca40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad46c825b930af0d5192dadb7332368a312fb82fb36a566c40d656ef23111303"

  strings:
    $s1  = "th.pow(Math.cos(737), 2) - 1)); while(true) { if(QfnahwmRL[xMrnqGxPkVv] > QmmMZ[xMrnqGxPkVv].length-(473+357)/830) { break; } if" ascii
    $s2  = "function MAzNTwpZzwmHjfIpx(QmmMZ){KUqBelgCbXZ= '';xMrnqGxPkVv=Math.round((Math.pow(Math.sin(440), 2) + Math.pow(Math.cos(440), 2" ascii
    $s3  = ") - 1));while(true){if (xMrnqGxPkVv >= (5097+711)/968){break;}QfnahwmRL[xMrnqGxPkVv]=Math.round((Math.pow(Math.sin(737), 2) + Ma" ascii
    $s4  = "ow(Math.cos(314), 2) - 1)));} QfnahwmRL[xMrnqGxPkVv]++;}xMrnqGxPkVv++;} return KUqBelgCbXZ}" fullword ascii
    $s5  = "function MAzNTwpZzwmHjfIpx(QmmMZ){KUqBelgCbXZ= '';xMrnqGxPkVv=Math.round((Math.pow(Math.sin(440), 2) + Math.pow(Math.cos(440), 2" ascii
    $s6  = "function wzzlWGF(pwmqEBMBzEdkawVXhAmdoQCbHRtfajJEjAdp) {return !KQJSPTyCyQC(TKfgJLxsAXmqyOK(pwmqEBMBzEdkawVXhAmdoQCbHRtfajJEjAdp" ascii
    $s7  = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii
    $s8  = "function BaxRe(XlcSoHWdzMi,AbyKfehnEMXSi,nfFQJoTl){iHFk=SJOxCVxuPEWhkFBhY(XlcSoHWdzMi,AbyKfehnEMXSi);hYUZG=iHFk.toString(nfFQJoT" ascii
    $s9  = "function QEITOMmvRIvSYXK(aTkVkyguZQXtcpVKp,rdqKrvmXrHnLzHgEPOFirEEekuYghquNvd,kZBnPvLcMsVJyThALIfUPfiUZHkwBxdTMBk){eval(aTkVkygu" ascii
    $s10 = "function BaxRe(XlcSoHWdzMi,AbyKfehnEMXSi,nfFQJoTl){iHFk=SJOxCVxuPEWhkFBhY(XlcSoHWdzMi,AbyKfehnEMXSi);hYUZG=iHFk.toString(nfFQJoT" ascii
    $s11 = "l);return hYUZG;}" fullword ascii
    $s12 = "function UCJqQbFaoMEqBFVbCwpHgxFQJihJccYrhJjuJNYXkzsgaNWkyUxvlO(BNoEPrLtDKFfy,CIFhgmBGnEkgLV){ return sdGLkhX[zqfdqtyB[BaxRe(BNo" ascii
    $s13 = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii
    $s14 = "function iWkqXaYttkpP(ekYVTqEOmUiaA) {return isFinite(ekYVTqEOmUiaA);}" fullword ascii
    $s15 = "function KQJSPTyCyQC(lqrZnIPxlErZmT) {return isNaN(lqrZnIPxlErZmT);}" fullword ascii
    $s16 = "function UCJqQbFaoMEqBFVbCwpHgxFQJihJccYrhJjuJNYXkzsgaNWkyUxvlO(BNoEPrLtDKFfy,CIFhgmBGnEkgLV){ return sdGLkhX[zqfdqtyB[BaxRe(BNo" ascii
    $s17 = "function V(hkOVWrLgkZBreq,MrFVZPgmulXVd,bXxEoXvjTku) {hkOVWrLgkZBreq[MrFVZPgmulXVd]=bXxEoXvjTku;}" fullword ascii
    $s18 = "function SJOxCVxuPEWhkFBhY(HUpCPsZeIC,isYucrRZtA) {return parseInt(HUpCPsZeIC,isYucrRZtA);}" fullword ascii
    $s19 = "function TKfgJLxsAXmqyOK(ONWAdKVomSezbzwRbeA) {return parseFloat(ONWAdKVomSezbzwRbeA);}" fullword ascii
    $s20 = "function wzzlWGF(pwmqEBMBzEdkawVXhAmdoQCbHRtfajJEjAdp) {return !KQJSPTyCyQC(TKfgJLxsAXmqyOK(pwmqEBMBzEdkawVXhAmdoQCbHRtfajJEjAdp" ascii

  condition:
    uint16(0) == 0x717a and
    8 of them
}