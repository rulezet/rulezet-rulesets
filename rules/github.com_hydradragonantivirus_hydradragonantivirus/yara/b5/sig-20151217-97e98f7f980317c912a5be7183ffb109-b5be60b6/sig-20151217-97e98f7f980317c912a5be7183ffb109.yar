rule sig_20151217_97e98f7f980317c912a5be7183ffb109 {
  meta:
    description = "datamaliciousorder - file 20151217_97e98f7f980317c912a5be7183ffb109.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13067283ea3a3f03ceee0aafd3ea757d8727eff5bffe71a47977d82e588951ab"

  strings:
    $s1  = ".pow(Math.cos(236), 2) - 1)); while(true) { if(gKGcXnmlL[jmpqZvByzWl] > VtYhq[jmpqZvByzWl].length-(-641+734)/93) { break; } if (" ascii
    $s2  = "function nuIHHnYzPErtHqftf(VtYhq){dRrOeurWwLC= '';jmpqZvByzWl=Math.round((Math.pow(Math.sin(17), 2) + Math.pow(Math.cos(17), 2) " ascii
    $s3  = "w(Math.cos(929), 2) - 1)));} gKGcXnmlL[jmpqZvByzWl]++;}jmpqZvByzWl++;} return dRrOeurWwLC}" fullword ascii
    $s4  = "- 1));while(true){if (jmpqZvByzWl >= (4689+153)/807){break;}gKGcXnmlL[jmpqZvByzWl]=Math.round((Math.pow(Math.sin(236), 2) + Math" ascii
    $s5  = "function nuIHHnYzPErtHqftf(VtYhq){dRrOeurWwLC= '';jmpqZvByzWl=Math.round((Math.pow(Math.sin(17), 2) + Math.pow(Math.cos(17), 2) " ascii
    $s6  = "function jFoxKED(UteCGUrdlpctHWTlyrrzOuhiIKyvAoJAEjrb) {return !QPELIxhMMhf(IgiGEyLHggSewav(UteCGUrdlpctHWTlyrrzOuhiIKyvAoJAEjrb" ascii
    $s7  = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s8  = "function aBxzP(FXPXzsqzQSw,hSkGuMCtwBlMn,UmyRGDoV){HWoc=oxwuvQTjnQnRpxEmd(FXPXzsqzQSw,hSkGuMCtwBlMn);SoEZd=HWoc.toString(UmyRGDo" ascii
    $s9  = "function GaTVdgxXXNvMfUzXKXfoECQUTIUXfaENeAcsKDfYKbJVbIrnxwtlQD(MCqytmuyKRKNS,bPPnuLcQBYYOtV){ return RNjuWwj[SnaWSbEi[aBxzP(MCq" ascii
    $s10 = "function OINwHKufySQNFkd(DDabOMnnWzgGmppUb,YzrcZdytLFsdIQClnZsDwuqcOrFveWDQlh,ewMiuPdOYQwuqdBTjRvFDJiRAEOLrikaBNu){eval(DDabOMnn" ascii
    $s11 = "function oVEaMunxMLKZ(pMTXaHbNMScWC) {return isFinite(pMTXaHbNMScWC);}" fullword ascii
    $s12 = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s13 = "function p(qJoiaGLUwCvw,scGfrAAXqPZRRa){qJoiaGLUwCvw.push(scGfrAAXqPZRRa);}" fullword ascii
    $s14 = "function k(brquPTTMtDPVYS,RdRAEzJzeeUji,RZEccKqDneL) {brquPTTMtDPVYS[RdRAEzJzeeUji]=RZEccKqDneL;}" fullword ascii
    $s15 = "function OINwHKufySQNFkd(DDabOMnnWzgGmppUb,YzrcZdytLFsdIQClnZsDwuqcOrFveWDQlh,ewMiuPdOYQwuqdBTjRvFDJiRAEOLrikaBNu){eval(DDabOMnn" ascii
    $s16 = ",'x','q','2','V','s','H','u','W','$','k','X','@','>','&','Y','P','%','Q','#','Z',']',' ','w','j','y','8','[','4','m','H',String." ascii
    $s17 = "function QPELIxhMMhf(SqvQFBKIziMNuh) {return isNaN(SqvQFBKIziMNuh);}" fullword ascii
    $s18 = "function aBxzP(FXPXzsqzQSw,hSkGuMCtwBlMn,UmyRGDoV){HWoc=oxwuvQTjnQnRpxEmd(FXPXzsqzQSw,hSkGuMCtwBlMn);SoEZd=HWoc.toString(UmyRGDo" ascii
    $s19 = "function oxwuvQTjnQnRpxEmd(fHmIGDHgKj,OJavZCcDyZ) {return parseInt(fHmIGDHgKj,OJavZCcDyZ);}" fullword ascii
    $s20 = "function jFoxKED(UteCGUrdlpctHWTlyrrzOuhiIKyvAoJAEjrb) {return !QPELIxhMMhf(IgiGEyLHggSewav(UteCGUrdlpctHWTlyrrzOuhiIKyvAoJAEjrb" ascii

  condition:
    uint16(0) == 0x6e53 and
    8 of them
}