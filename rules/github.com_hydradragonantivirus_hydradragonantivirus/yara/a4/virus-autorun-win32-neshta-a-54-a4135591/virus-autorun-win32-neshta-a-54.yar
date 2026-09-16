rule Virus_Autorun_Win32_Neshta_A_54 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_54.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6046e271bfa3ba8679ffe8eaa53b74c032f05c78290f8922f093ed9d378154fe"

  strings:
    $x1  = " */(()=>{\"use strict\";const e=\"SESSION_STORE\",t=\"GET_BK_GLOBALS\",a=\"PING_CONTENT_APS_OBSERVER\",n={NONE:0,LINKEDIN:1,INST" ascii
    $x2  = "tLoaded\",e))}}class se{static PreprocessSecureSearchRegEx(e){return e.trim().split(\"\\n\")}static getBrowserSuffix(){const{CH:" ascii
    $x3  = "dow: #000 1px 1px;\";console.log(`%cDEBUG - ${o}`,e,l,r)}};class ne{constructor(e){this.pingCommand=e,this.basePingListener(),th" ascii
    $s4  = "nsole.log(`%cWARN - ${o}`,e,l,r)}if(n>=Y&&t===Q){const e=\"color: #FF33D7; font-family: sans-serif; font-weight: bolder; text-sh" ascii
    $s5  = "if(n===this.pingCommand)return te.debug(`File Injection [pinged]: Received ${n} command`),a({content:!0}),\"function\"==typeof e" ascii
    $s6  = "PT_GENERATED_DEFAULT_SS_URL${re}`,value:\"\"},SECURE_SEARCH_REGEXES:{scope:oe,name:\"SECURE_SEARCH_REGEXES\",value:\"\",preproce" ascii
    $s7  = "ame:\"*CounterPagesBlocked\",value:0},DOWNLOADS_SCANNED:{scope:ie,name:\"*CounterDownloadsScanned\",value:0},DOWNLOADS_BLOCKED:{" ascii
    $s8  = "PreprocessSecureSearchRegEx},SHOW_SEARCH_SETTINGS:{scope:ie,name:\"*ShowSearchSettings\",value:!0},SECURE_SEARCH_TOAST_STAMP:{sc" ascii
    $s9  = "{\"group\":\"NelM365CDNUpload1\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://M365CDN.nel.measure.office.net/api/report?" ascii
    $s10 = "R:1},re=se.getBrowserSuffix(),le={DEV_MODE:{scope:ie,name:\"dev_mode\",value:!1},AFF_ID:{scope:ie,name:\"*Affid\",value:0},BINAR" ascii
    $s11 = "lue:\"\",writeOnly:!0},BROWSER_TYPE:{scope:ie,name:\"browsertype\",value:\"\",writeOnly:!0},USER_AGENT:{scope:ie,name:\"useragen" ascii
    $s12 = "tLoaded\",e))}}class se{static PreprocessSecureSearchRegEx(e){return e.trim().split(\"\\n\")}static getBrowserSuffix(){const{CH:" ascii
    $s13 = "e:ie,name:\"*CounterDownloadsBlocked\",value:0},BLOCKPAGE_WHITELIST:{scope:oe,name:\"*WhiteList\",value:\"\"},TS_WHITELIST:{scop" ascii
    $s14 = ":t,EDGE:a}={CH:\"_ch\",FF:\"_ff\",IE:\"_ie\",EDGE:\"_ed\"},n={};return n[T]=a,n[S]=t,n[_]=e,n[I]}}const{SYSTEM:ie,USER:oe}={SYST" ascii
    $s15 = "le.log(o,l,r),n>=V&&t===J){const e=\"color: #FFA500; font-family: sans-serif; font-weight: bolder; text-shadow: #000 1px 1px;\";" ascii
    $s16 = "e:\"\",writeOnly:!0},SUGGESTION_URL:{scope:ie,name:\"suggestion_url\",value:\"\"},SCRIPT_GENERATED_DEFAULT_SS_URL:{scope:oe,name" ascii
    $s17 = "ation_options${re}`,value:0,writeOnly:!0},PAGES_SCANNED:{scope:ie,name:\"*CounterPagesScanned\",value:0},PAGES_BLOCKED:{scope:ie" ascii
    $s18 = "e(),!0}))}addIdentifier(){var e;e=()=>{const e=document.createElement(\"span\");e.id=this.pingCommand,e.style.cssText=\"display:" ascii
    $s19 = "rtyTrackers:b.name};const W=0,G=0,$=1,M=2,V=3,Y=4,K=1,X=2,J=3,Q=4,Z={BACKGROUND:\"BACKGROUND\",CONTENT:\"CONTENT\",TELEMETRY:\"T" ascii
    $s20 = "https://res.cdn.office.net/owamail/hashed-v1/resources/locale/pt/owa.143371.m.3c9ef1ce.json{\"cEhCR\":\"Dia inteiro\",\"Kdpbtc\"" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}