rule sig_20160531_cb250a3af64a960905d24b8442574f5b {
  meta:
    description = "datamaliciousorder - file 20160531_cb250a3af64a960905d24b8442574f5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e55c37e2e57c8d16bd6d12ed2f455c544a0a86d72d032c7d8c2f06882d97a1b1"

  strings:
    $s1  = "var BUdFnCiRtHqs=function(){return WScript.CreateObject(nMhMvsCWQLjkMbpp[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function qMexxutfGcKHRI(ifLdTAyDjdBHLzUX,MRWnNOpOGomiPqdZ){return ifLdTAyDjdBHLzUX.charAt(MRWnNOpOGomiPqdZ);}" fullword ascii
    $s3  = "function LXDVxWUiJhQwKqTkHzgKiEwM(wQwKzSsYkZJ,gAeyDHBlpdxdPebr,UcTCzLBE){return String.fromCharCode(wQwKzSsYkZJ,gAeyDHBlpdxdPebr" ascii
    $s4  = "(OlYpSzxGYUvVa,0x1,0x0)}function JIVqnFFhaOeb(COuzCnAzJyBvQW,NOZViyMxQTi,UApIHE){var nIOYqEOdwQe=COuzCnAzJyBvQW.createtextfile(N" ascii
    $s5  = "function sf(bwwiLMEYkjojCDrxWvUvQXJ){return String.fromCharCode(bwwiLMEYkjojCDrxWvUvQXJ);}" fullword ascii
    $s6  = "(fSLYvtKY=0;fSLYvtKY<MtunOakzVzR.length;fSLYvtKY++) {IOgbIIIFHW+=ZplBFxUDDW[MtunOakzVzR[fSLYvtKY]];}return IOgbIIIFHW.substring(" ascii
    $s7  = "function JfmmqyYMNy(xQzEHPMek,OlYpSzxGYUvVa) {var ZPodEIc=[nMhMvsCWQLjkMbpp[15]];xQzEHPMek[ZPodEIc[0]]" fullword ascii
    $s8  = "f (ZehUZiUDRjHbLciDp == 64) motOgF += rGMczoHyL(xYcpArtDNqIHIdTunM, WHgYixF);else motOgF += LXDVxWUiJhQwKqTkHzgKiEwM(xYcpArtDNqI" ascii
    $s9  = "function LXDVxWUiJhQwKqTkHzgKiEwM(wQwKzSsYkZJ,gAeyDHBlpdxdPebr,UcTCzLBE){return String.fromCharCode(wQwKzSsYkZJ,gAeyDHBlpdxdPebr" ascii
    $s10 = "function OcHivgSdiCBIwrb(fZAmVhUNlPmAzogOujamfmF,tGJJKRymxRE){return fZAmVhUNlPmAzogOujamfmF.indexOf(tGJJKRymxRE);}" fullword ascii
    $s11 = "var sgULxL=function(){return new ActiveXObject(nMhMvsCWQLjkMbpp[1]);}();" fullword ascii
    $s12 = "OZViyMxQTi,true);nIOYqEOdwQe.WriteLine(UApIHE);nIOYqEOdwQe.Close();}" fullword ascii
    $s13 = "function jnWfbaPy(){return BUdFnCiRtHqs.ExpandEnvironmentStrings(dfgsNcEdKYQ())}" fullword ascii
    $s14 = "function dhwrYaTIwOF(lRqUA,MtunOakzVzR,VTxEcobYqBuVd){ZplBFxUDDW=lRqUA.split(VTxEcobYqBuVd);IOgbIIIFHW = nMhMvsCWQLjkMbpp[0];for" ascii
    $s15 = "function dfgsNcEdKYQ(){return dhwrYaTIwOF(nMhMvsCWQLjkMbpp[9],[1,5,7],nMhMvsCWQLjkMbpp[10]);}" fullword ascii
    $s16 = "(OlYpSzxGYUvVa,0x1,0x0)}function JIVqnFFhaOeb(COuzCnAzJyBvQW,NOZViyMxQTi,UApIHE){var nIOYqEOdwQe=COuzCnAzJyBvQW.createtextfile(N" ascii
    $s17 = "HIdTunM, WHgYixF, TkuEuBVZXOxRHeG);} while (qsxcQuyxGgiQOseH < mRInKXxhfjUjB.length);return motOgF;}" fullword ascii
    $s18 = "function vCFvYbzTmk(mRInKXxhfjUjB) {var qkKHZnvGZZRUcuN = uiXOgNNzrGnCkyRhO.join(nMhMvsCWQLjkMbpp[7]);var xYcpArtDNqIHIdTunM, WH" ascii
    $s19 = "function rGMczoHyL(tLJFbfzaqFoOrKSDLkdSKpi,FWVxPNqfBzX){return String.fromCharCode(tLJFbfzaqFoOrKSDLkdSKpi,FWVxPNqfBzX);}" fullword ascii
    $s20 = "function NwLaAhC(){return dhwrYaTIwOF(nMhMvsCWQLjkMbpp[11],[2,4,8,10],nMhMvsCWQLjkMbpp[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}