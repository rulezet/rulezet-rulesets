rule sig_20151208_285c13728902e8101f31ae4311ad7f48 {
  meta:
    description = "datamaliciousorder - file 20151208_285c13728902e8101f31ae4311ad7f48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4266877b8baa20e04d1eb6b570fc53fa7c7fbb6e6575e64eb934b6808de31777"

  strings:
    $s1  = "function ZoxfQAY(UrisSihkvBpbNIBskdwGHHIcjKaOKfFIiqyw) {return !isNaN(parseFloat(UrisSihkvBpbNIBskdwGHHIcjKaOKfFIiqyw)) && isFin" ascii
    $s2  = "function ZoxfQAY(UrisSihkvBpbNIBskdwGHHIcjKaOKfFIiqyw) {return !isNaN(parseFloat(UrisSihkvBpbNIBskdwGHHIcjKaOKfFIiqyw)) && isFin" ascii
    $s3  = "push(\"77\");m.push(\"76\");m.push(\"72\");m.push(\"34\");m.push(\"59\");m.push(\"13\");m.push(\"10\");m.push(\"118\");m.push(\"" ascii
    $s4  = "function fyiuxqIvPgFYOQoHdpydCEPiviywYmBgtXGjvgHWngFAesHxjHjQnp(CGDwUEsbwmtdB,IhBHLEyIxcPrhO){ return EtVZbFiNUpYdw[tfBxk(CGDwUE" ascii
    $s5  = "push(\"75\");E.push(\"66\");E.push(\"119\");E.push(\"70\");E.push(\"84\");E.push(\"43\");E.push(\"47\");E.push(\"42\");E.push(\"" ascii
    $s6  = "push(\"41\");E.push(\"59\");E.push(\"32\");E.push(\"105\");E.push(\"102\");E.push(\"32\");E.push(\"40\");E.push(\"65\");E.push(" ascii
    $s7  = ";return PmXnZ;}function aQTHsEflARzcKVo(WiTNWebGxozLZCYaG){eval(WiTNWebGxozLZCYaG)}" fullword ascii
    $s8  = "push(\"32\");E.push(\"49\");E.push(\"41\");E.push(\"32\");E.push(\"32\");E.push(\"123\");E.push(\"13\");E.push(\"10\");E.push(\"" ascii
    $s9  = "function fyiuxqIvPgFYOQoHdpydCEPiviywYmBgtXGjvgHWngFAesHxjHjQnp(CGDwUEsbwmtdB,IhBHLEyIxcPrhO){ return EtVZbFiNUpYdw[tfBxk(CGDwUE" ascii
    $s10 = "push(\"54\");m.push(\"49\");m.push(\"55\");m.push(\"50\");m.push(\"48\");m.push(\"117\");m.push(\"77\");m.push(\"51\");m.push(\"" ascii
    $s11 = "push(\"102\");E.push(\"32\");E.push(\"40\");E.push(\"83\");E.push(\"69\");E.push(\"46\");E.push(\"115\");E.push(\"116\");E.push(" ascii
    $s12 = "rTRfj)}function tfBxk(cUPMUHzdVVf,SdUEtdYMyhUwd,VxumRzqa){WYpT=parseInt(cUPMUHzdVVf,SdUEtdYMyhUwd);PmXnZ=WYpT.toString(VxumRzqa)" ascii
    $s13 = "push(\"32\");E.push(\"32\");E.push(\"32\");E.push(\"32\");E.push(\"32\");E.push(\"32\");E.push(\"65\");E.push(\"101\");E.push(\"" ascii
    $s14 = "function VEFaoFUYLvz(NYmGOHNE,lsHmSq){return NYmGOHNE.split(lsHmSq)}" fullword ascii
    $s15 = "push(\"123\");E.push(\"13\");E.push(\"10\");E.push(\"32\");E.push(\"32\");E.push(\"32\");E.push(\"32\");E.push(\"32\");E.push(\"" ascii
    $s16 = "RMIFguNu[RvbNRFMMmxl]=(-442+442)/333; while(true) { if(rRMIFguNu[RvbNRFMMmxl] > IuUIz[RvbNRFMMmxl].length-(258+63)/321) { break;" ascii
    $s17 = "function certHDokNaHcIIblX(IuUIz){yuQRITeihQi= '';for(RvbNRFMMmxl=(-287+287)/153; RvbNRFMMmxl < (-39+719)/340; RvbNRFMMmxl++) {r" ascii
    $s18 = "var EtVZbFiNUpYdw=[];for(MjrTRfj=(-661+661)/499;MjrTRfj<(71366+698)/563;MjrTRfj++){EtVZbFiNUpYdw[MjrTRfj]=String.fromCharCode(Mj" ascii
    $s19 = "push(\"45\");m.push(\"105\");m.push(\"110\");m.push(\"99\");m.push(\"108\");m.push(\"117\");m.push(\"100\");m.push(\"101\");m.pu" ascii
    $s20 = "push(\"78\");E.push(\"54\");E.push(\"118\");E.push(\"81\");E.push(\"53\");E.push(\"49\");E.push(\"80\");E.push(\"75\");E.push(\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}