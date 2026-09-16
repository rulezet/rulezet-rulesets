rule sig_20160525_6a6610dff9605dfe0cd6490e92a528d9 {
  meta:
    description = "datamaliciousorder - file 20160525_6a6610dff9605dfe0cd6490e92a528d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcd4758812d24b26b6e8cbf550494de119ce523069f80289986b3269509f3f23"

  strings:
    $s1  = "ath.cos(307), 2) - 1))-293) & 0xff;sdXWNB = oSMebppDuwMHrvwKnVW>> (752 + Math.round((Math.pow(Math.sin(761), 2) + Math.pow(Math." ascii
    $s2  = "in(392), 2) + Math.pow(Math.cos(392), 2) - 1))-37)) oMnMcwMCwKuv += ik(WTiauOoBFspRmvGWOqxyp);else if (KRulmSjZHilaGQRtrwslFWy =" ascii
    $s3  = "function sgwoIqDWtP(ZrxvurASERPcH) {var pEqvFQ = HazKeDHqXVrZUTLhCQsB.join(KMGAKlp[0]);var WTiauOoBFspRmvGWOqxyp, sdXWNB, hvdrve" ascii
    $s4  = "function aACTfXroKKi(aHWDwqaYdlSDeXc,sQVozPGFwmZyCnmdwycUvsNu){return aHWDwqaYdlSDeXc.charAt(sQVozPGFwmZyCnmdwycUvsNu);}" fullword ascii
    $s5  = "y = ammXPjrbyxDhLa(pEqvFQ,aACTfXroKKi(ZrxvurASERPcH,hIPOWHbvyDVqp++));oSMebppDuwMHrvwKnVW = PgPrJCWOo<< (553 + Math.round((Math." ascii
    $s6  = "function KCYtKTcHgUGH(bVXWxgxzwajKSVtK,bRKqLfwj,PmrXpQRmGPqKQFB){return String.fromCharCode(bVXWxgxzwajKSVtK,bRKqLfwj,PmrXpQRmGP" ascii
    $s7  = "uOoBFspRmvGWOqxyp, sdXWNB);else oMnMcwMCwKuv += KCYtKTcHgUGH(WTiauOoBFspRmvGWOqxyp, sdXWNB, hvdrveJnOfesesCqGxXj);} while (hIPOW" ascii
    $s8  = "function ik(bzFuHTVwnXTAcfgRJWIRkjm){return String.fromCharCode(bzFuHTVwnXTAcfgRJWIRkjm);}" fullword ascii
    $s9  = "function KCYtKTcHgUGH(bVXWxgxzwajKSVtK,bRKqLfwj,PmrXpQRmGPqKQFB){return String.fromCharCode(bVXWxgxzwajKSVtK,bRKqLfwj,PmrXpQRmGP" ascii
    $s10 = "function sgwoIqDWtP(ZrxvurASERPcH) {var pEqvFQ = HazKeDHqXVrZUTLhCQsB.join(KMGAKlp[0]);var WTiauOoBFspRmvGWOqxyp, sdXWNB, hvdrve" ascii
    $s11 = "function ammXPjrbyxDhLa(lSRaSavousPLClisQYg,LHUgo){return lSRaSavousPLClisQYg.indexOf(LHUgo);}" fullword ascii
    $s12 = "function KGDNrVvJsNoLarxtF(QqDBWkTQgdTNsMQvumDxGQZ,eXMiQzxNkiNsXEfzii){return String.fromCharCode(QqDBWkTQgdTNsMQvumDxGQZ,eXMiQz" ascii
    $s13 = "function KGDNrVvJsNoLarxtF(QqDBWkTQgdTNsMQvumDxGQZ,eXMiQzxNkiNsXEfzii){return String.fromCharCode(QqDBWkTQgdTNsMQvumDxGQZ,eXMiQz" ascii
    $s14 = "HbvyDVqp < ZrxvurASERPcH.length);return oMnMcwMCwKuv;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}