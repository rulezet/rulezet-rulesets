rule Virus_Autorun_Win32_Neshta_A_26 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35ca31a8c987de14948d8f01f37c807df75baf6e5516df146bc82e1d8bbf34a5"

  strings:
    $s1  = "o falharam. Consulte o https://recover.microsoft.com/reinstall para obter instru" fullword wide
    $s2  = "Alle pogingen om deze installatie te herstellen, zijn mislukt. Ga naar https://recover.microsoft.com/reinstall voor instructies " wide
    $s3  = " til https://recover.microsoft.com/reinstall for instruksjoner om hvordan du gjenoppretter data maskinen manuelt." fullword wide
    $s4  = " till https://recover.microsoft.com/reinstall om du vill ha information om hur du " fullword wide
    $s5  = "n. Ve a https://recover.microsoft.com/reinstall para obtener instrucciones sobre c" fullword wide
    $s6  = " https://recover.microsoft.com/reinstall pour obtenir des instructions sur la proc" fullword wide
    $s7  = "%1!s!  %2!u!%%.Uw organisatie beheert de update-instellingen.sDe computer wordt mogelijk meerdere keren opnieuw opgestart om upd" wide
    $s8  = "Forbereder system" fullword wide
    $s9  = "Kopierer filer!Installerer funktioner og drivere" fullword wide
    $s10 = "Kopierer filer!Installerer funksjoner og drivere" fullword wide
    $s11 = "i manual computerul." fullword wide
    $s12 = "Se produjo un error en todos los intentos de recuperar esta instalaci" fullword wide
    $s13 = "ndt og tilsluttet.,Computeren genstartes muligvis et par gange." fullword wide
    $s14 = "%1!s!  %2!u!%%=Din organisation administrerer dine opdateringsindstillinger.WComputeren genstarter muligvis nogle gange for at a" wide
    $s15 = "Updates worden uitgevoerd-Houd de computer ingeschakeld en aangesloten.<De computer wordt mogelijk meerdere keren opnieuw opgest" wide
    $s16 = "rile de actualizare.XComputerul poate reporni de c" fullword wide
    $s17 = "%1!s!  %2!u!%%/Your organisation manages your update settings.LYour computer may restart a few times to apply updates before it " wide
    $s18 = "A reiniciar,Insira o suporte de dados externo e prima OK" fullword wide
    $s19 = "rer le support de stockage externe, puis appuyer sur OK" fullword wide
    $s20 = " jour<Veuillez garder votre ordinateur portable activ" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}