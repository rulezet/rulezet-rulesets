rule sig_20170125_5b169abf528260f9b818d4d64228e417 {
  meta:
    description = "datamaliciousorder - file 20170125_5b169abf528260f9b818d4d64228e417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d475414a02bcf90dda0b670b13b06fdc5b9595c4d5cc094003da9f2e741fdf64"

  strings:
    $s1  = "function inuquccekvihlytxurvynuwwedxizpazvacmuhugkureldottononduduqowhiraketloginylmuwyjnoltimmu() {" fullword ascii
    $s2  = "return [ /*irhux*/ , WScript, /*inz*/ , /*enhyn*/ , /*zkago*/ , /*zuxy*/ ][1];" fullword ascii
    $s3  = "return [ /*umtu*/ , /*iwz*/ , /*ovny*/ , \"C:\", /*ky*/ ];" fullword ascii
    $s4  = "function zyfcupalykmilmagcikryncorunupaloxbinotuldirygixysxalnimitxiracgew() {" fullword ascii
    $s5  = "var mykejho = wrahavinocwewovrupuldubihuqozbicgyciwejsidohpiwampopyrexexfummaqsohxiz()[[ /*ykqicm*/ , 1, /*cob*/ , /*fhojqu*/ , " ascii
    $s6  = "function dsorhaqhiqomsogqyqjupeflofgawuhtelrofyznejiqgatyzywramexyzfodbyjexozegetawhi() {" fullword ascii
    $s7  = "return [ /*fxemko*/ , \"Get\", /*yqxoz*/ , /*fe*/ , /*zihk*/ ];" fullword ascii
    $s8  = "function ntepgovijgetefehugybezvosakivaclyqkashoninunorgupelinvomahuvwaduggiwsu() {" fullword ascii
    $s9  = "function owyrrekipxoxusezizmykeladsovyrnonowecesgespybxuqemgesygodufcojsojijkobunarucyncog() {" fullword ascii
    $s10 = "return [ /*tjacp*/ , /*axmygv*/ , /*unqi*/ , \"dr\", /*ytlogz*/ ];" fullword ascii
    $s11 = "function nyvezitrygetdoqikpojweljaqozerewirmidsujeqakolvebjeziwunehibuhylez() {" fullword ascii
    $s12 = "function ilevjoxydturygmospyjeroduzadbudnifelrokcylcuralepapysjenixaxnugdyfolypowavycz() {" fullword ascii
    $s13 = "function ezqiggutpexmobyjynkurwerforulobyzkekdibfevarikolgircuxlorotcigqesecka() {" fullword ascii
    $s14 = "return [ /*cjanwy*/ , \"Get\"];" fullword ascii
    $s15 = "return [ /*hbezpo*/ , \"GET\", /*ulg*/ , /*pvini*/ ];" fullword ascii
    $s16 = "var otulruk0 = etricfihduhvybdizcukosqelyhcazjuzzotrakacarcijujsytodidicdijupygopykpapi()[[0, /*ylb*/ , /*wire*/ ][0]] + ihecemo" ascii
    $s17 = "function ekcidzokqygejbyniwxyjjahmohturcoftucsogydytgetpijoboddixazulzodloqwumattyktydgig() {" fullword ascii
    $s18 = "ubvyfewwu()[[2, /*otwi*/ , /*zhuwu*/ , /*ring*/ , /*ti*/ ][0]] + pojkixafucotuhpewuqfyhmavoxluqmibmifsigezywokqydonefuvvaredoluk" ascii
    $s19 = ", /*bilo*/ , 0][3]] + yghuryqupodaligzyjezxarjalymimbofpeczywadubyrecokajpunwimnunoxugumivobwafpi()[[ /*vtu*/ , 0, /*ben*/ ][1]]" ascii
    $s20 = "function epussopanamrudsopuvcohywtimxuxabwarxupyhmucebcomdevexytylyvmutgojukwijitedgubqo() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}