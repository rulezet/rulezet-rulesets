rule sig_20160531_4601ef777b17040902c2bbf80a7f0a5c {
  meta:
    description = "datamaliciousorder - file 20160531_4601ef777b17040902c2bbf80a7f0a5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fcb1d77894489228f5e39351007d6ee131d5d09d5bafd0afef1e2df746a2667"

  strings:
    $s1  = "var AjWZtISUCrexn=function(){return WScript.CreateObject(svzOYzUQdaBBgBMwuMCdXmwM[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" ascii
    $s2  = "function sADBgKZorOnMbOMqZOdn(sGEqgWIobR,eCdVEmVZZAwXTXytAdu){return sGEqgWIobR.charAt(eCdVEmVZZAwXTXytAdu);}" fullword ascii
    $s3  = "waWra, XujuuUkVdkbwDs, zIGYfh, ABKGRpdVQ, kgcMSrkqD, BCOOs, oErWwamnEuPDKtWUykl, lOBeXkIcBbyqfeW, RqYpXydLirvLOEhnLEeoA=0, LeAvE" ascii
    $s4  = "(vbUqVBrF,0x1,0x0)}function yPReXEpPeH(XuAdRObck,XdxqIcKQYU,juXlzBEDWAl){var PHFqAnhuavspSr=XuAdRObck.createtextfile(XdxqIcKQYU," ascii
    $s5  = "function rSGKEs(mHEVibxtXB,ZHpYuqMlzsOFWk,FWmxy){XSOQxGK=mHEVibxtXB.split(FWmxy);mXOjHVvsNJ = svzOYzUQdaBBgBMwuMCdXmwM[0];for(nn" ascii
    $s6  = "tJB=0;nntJB<ZHpYuqMlzsOFWk.length;nntJB++) {mXOjHVvsNJ+=XSOQxGK[ZHpYuqMlzsOFWk[nntJB]];}return mXOjHVvsNJ.substring(3,mXOjHVvsNJ" ascii
    $s7  = "kbwDs, zIGYfh);} while (RqYpXydLirvLOEhnLEeoA < QeccyqLhNNGTm.length);return LeAvEtpYATcgy;}" fullword ascii
    $s8  = "true);PHFqAnhuavspSr.WriteLine(juXlzBEDWAl);PHFqAnhuavspSr.Close();}" fullword ascii
    $s9  = "var miWbKVhC=function(){return new ActiveXObject(svzOYzUQdaBBgBMwuMCdXmwM[1]);}();" fullword ascii
    $s10 = "function at(keNku){return String.fromCharCode(keNku);}" fullword ascii
    $s11 = "function xponrKd(){return rSGKEs(svzOYzUQdaBBgBMwuMCdXmwM[11],[2,4,8,10],svzOYzUQdaBBgBMwuMCdXmwM[12]);}" fullword ascii
    $s12 = "GYfh = lOBeXkIcBbyqfeW & 0xff;if (BCOOs == 64) LeAvEtpYATcgy += at(nFgIQQoXKZwwaWra);else if (oErWwamnEuPDKtWUykl == 64) LeAvEtp" ascii
    $s13 = "function vIFKDD(){return rSGKEs(svzOYzUQdaBBgBMwuMCdXmwM[9],[1,5,7],svzOYzUQdaBBgBMwuMCdXmwM[10]);}" fullword ascii
    $s14 = "function yJYwu(RqRvnZphWIERRrEmjGv,ETSxdQJww){return RqRvnZphWIERRrEmjGv.indexOf(ETSxdQJww);}" fullword ascii
    $s15 = "function rSGKEs(mHEVibxtXB,ZHpYuqMlzsOFWk,FWmxy){XSOQxGK=mHEVibxtXB.split(FWmxy);mXOjHVvsNJ = svzOYzUQdaBBgBMwuMCdXmwM[0];for(nn" ascii
    $s16 = "(vbUqVBrF,0x1,0x0)}function yPReXEpPeH(XuAdRObck,XdxqIcKQYU,juXlzBEDWAl){var PHFqAnhuavspSr=XuAdRObck.createtextfile(XdxqIcKQYU," ascii
    $s17 = "function sNoMzpE(){return AjWZtISUCrexn.ExpandEnvironmentStrings(vIFKDD())}" fullword ascii
    $s18 = "function dapIFqGPf(zLQSB,YXXqUbNEMyB){return String.fromCharCode(zLQSB,YXXqUbNEMyB);}" fullword ascii
    $s19 = "function EArCrVhvNz(){return rSGKEs(svzOYzUQdaBBgBMwuMCdXmwM[13],[0,3,6],svzOYzUQdaBBgBMwuMCdXmwM[14]);}" fullword ascii
    $s20 = "YATcgy += dapIFqGPf(nFgIQQoXKZwwaWra, XujuuUkVdkbwDs);else LeAvEtpYATcgy += mUVJOqRReCbtkgvXvMpOThTQ(nFgIQQoXKZwwaWra, XujuuUkVd" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}