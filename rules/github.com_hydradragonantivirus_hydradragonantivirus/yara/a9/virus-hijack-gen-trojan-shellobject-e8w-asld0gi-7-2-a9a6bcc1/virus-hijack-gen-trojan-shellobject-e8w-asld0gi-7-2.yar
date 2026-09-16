rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "299f191aa3decd3256c9c3522dd444321db8b45a49109ecd3ad14c57d6eccdb2"

  strings:
    $s1  = "Vuyubokejuniku dihu bekopukafo lozepiyiwa. Yayehacubenegi jugudane pikotigo dimuwuso. Cudiwuzemike vasohiro vacopi sagibepisato." ascii
    $s2  = "Zoyi fuwupivizimaja kacanaluhi. Buzolufafo rafodu jugifoyuniceki. Nobemi to kuwa. Citixahaluxu lugezelokaxefa molaliye vexefakiw" ascii
    $s3  = "evi cezakowukewo fejave hebajigiviha. Zifu yacizogizanugi payacu cipi wetewavasa. Loge juxosidijoha ruxayo gorayociceneho zogole" ascii
    $s4  = "umigesa kukixo. Yefepuwa. Hu jecu getutunivilera. Luwafujojoxa rukulura zapunekuce dolapedubo jirehebetajeda. Raguluyodawo. Hura" ascii
    $s5  = "KGifakeku honivasowomaza jitezapuvayito lohu rejevu tusibebici xidusawe rice" fullword wide
    $s6  = "amozigo haxafaze. Nevidizaho kaledetice go. Dace gudo. Hakomojewe hogidipo kafusucojaxifo gujeyi. Tabemojeyu zebazobupu. Yo bume" ascii
    $s7  = "zimosafodidu sepe. Jacuda gemuva falo miseyicuwatita. Kone yepijosu dotakupo vetemulavi. Fiposoxo hiluju sucufususa boheni. Hide" ascii
    $s8  = "iho hi cefogavoha zo. Bugukuwutikefe vasuke. Nahewehovema riwiku jinucewuza zaludavakofa. Fahofecuzaloci tote bosi. Nimus" fullword ascii
    $s9  = "TODO: layout OLE  property page" fullword wide
    $s10 = "@Cozazu susezebonulise tusida fohixeka hoti yiwifuvudamoni xuxaho" fullword wide
    $s11 = "Copyright (C) 2017, apylumzim" fullword wide
    $s12 = "m cannot be run in DOS mode." fullword ascii
    $s13 = "!This " fullword ascii
    $s14 = "iho wu socegutosi. Xuxacojofodago luhi. Tokihonize zigesojevi loha mocugorozota hujamijuruku. Kiyi pucajetutoloru bewomape bokaz" ascii
    $s15 = "juhojoji. Nupu cayiru. Redopofo. Xobanijo dirivufemaxusu. Nutavecehenube puhugu wujejixafu pace. Lunu yifunogacebora coyenu. Sal" ascii
    $s16 = ". Curemaxojose. Wumajamepozo teramexizosi makeluxepuvemi ra. Zeleri nekaba tigisojeroje. Zotolu pasisu. Limu rimejozuzuyuwa koca" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}