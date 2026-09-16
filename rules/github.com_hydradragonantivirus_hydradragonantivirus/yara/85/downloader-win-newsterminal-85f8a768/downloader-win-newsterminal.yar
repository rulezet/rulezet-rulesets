rule downloader_win_newsterminal {
  meta:
    id             = "2f9aae45-e3bd-4d87-b336-5d141738952b"
    version        = "1.0"
    description    = "Detect the PowerShell based downloader used by APT42 called NEWSTERMINAL"
    author         = "Sekoia.io"
    creation_date  = "2024-08-26"
    classification = "TLP:CLEAR"
    hash           = "2b756515400d7e3b6e21ee3a83f313c8"

  strings:
    $ = "Start-Process -FilePath $takeownCommand -ArgumentList $takeownArgs -Wait -NoNewWindow"
    $ = "function Download-And-Extract-Dll {"
        $ = "$icaclsArgs = $destinationFilePath, \"/grant\", \"Administrators:F\", \"/c\", \"/q\""
    $ = "$publicip=(iwr http://127.0.0.1:4040/api/tunnels"

  condition:
    1 of them and filesize < 30KB
}