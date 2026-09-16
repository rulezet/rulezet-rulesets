import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_6_2_Virus_Hijac_114 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_41.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aed769307e38ba23233c9e5bd676f009bcc5871cc4f6dd1447e662ca109bd72d"
    hash2       = "379fa155bfa927347e6d6da7a3949837c9bd7fb80119359f8045ef0bfcda3eeb"
    hash3       = "67ef84dfef19e55a6c230a10a42f614fe523d062ea7f152c7a31b30b4f4a31ff"

  strings:
    $s1  = "leARPHELPLINKhttp://www.adobe.com/fr/support/main.htmlARPURLUPDATEINFOhttp://helpx.adobe.com/fr/reader.htmlAcroIEHelper_Descript" ascii
    $s2  = "pertoire TEMP de l'utilisateur.ISNetAPI.dll n'est pas charg" fullword ascii
    $s3  = "cution du correctif sur les fichiersFichier : [1]  Taille : [3] octetsProcessAbcpyTraitement du fichier Abcpy.ini en cours.Proce" ascii
    $s4  = "me d'exploitation NT et le chargement correct de NetApi32.DLL.Serveur introuvable. V" fullword ascii
    $s5  = " l'adresse http://www.adobe.com/go/reader_system_reqs_fr.OLE_VERB_OPEN&Ouvrir,0,2OpenWithOuvrir avec Adobe Acrobat Reader" fullword ascii
    $s6  = "ration peut prendre quelques minutes en fonction de la vitesse du processeur et de la configuration mat" fullword ascii
    $s7  = " disponibles sur le site www.adobe.com/fr. Adobe recommande le t" fullword ascii
    $s8  = "cuter ISScript.msi ou veuillez contacter le personnel de support.IS_COMPLUS_PROGRESSTEXT_COSTCalcul des co" fullword ascii
    $s9  = "cution du correctif sur les fichiersFichier : [1]  Taille : [3] octetsProcessAbcpyTraitement du fichier Abcpy.ini en cours.Proce" ascii
    $s10 = "ges suffisants pour modifier les permissions sur ce fichier.Les services de composants (COM+ 1.0) ne sont pas install" fullword ascii
    $s11 = "installation ne peut pas fermer un processus en cours d" fullword ascii
    $s12 = "mentaires.Erreur lors de l'annulation de l'inscription de l'application COM+. Contactez votre personnel de support technique pou" ascii
    $s13 = " niveau Internet Explorer, visitez le site www.microsoft.com.LC_UNSUPPORTED_OSLC_UNSUPPORTED_OS_1Impossible d" fullword ascii
    $s14 = "mentaires.Erreur lors de l'annulation de l'inscription de l'application COM+. Contactez votre personnel de support technique pou" ascii
    $s15 = "mentaires.Impossible de modifier la description pour le service '[2]' ([3]).Le service Windows Installer ne peut pas mettre " fullword ascii
    $s16 = "ation du fichier XML [2]. [3]Erreur lors du chargement des serveurs.Erreur lors du chargement de NetApi32.DLL. ISNetApi.dll requ" ascii
    $s17 = "ation du fichier XML [2]. [3]Erreur lors du chargement des serveurs.Erreur lors du chargement de NetApi32.DLL. ISNetApi.dll requ" ascii
    $s18 = "dias. Il est disponible sur les principales plates-formes de bureau et mobiles.ReadmeHtmlUNKNOWNPROCESSWITHIDProcessus inconnu a" ascii
    $s19 = "que de type pour le fichier [2]. Contactez votre service de support technique.Impossible d'annuler l'inscription de la biblioth" fullword ascii
    $s20 = "dias. Il est disponible sur les principales plates-formes de bureau et mobiles.ReadmeHtmlUNKNOWNPROCESSWITHIDProcessus inconnu a" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "67533f79a87f4ce08c671dedbb7cb801" and (8 of them)
    ) or (all of them)
}