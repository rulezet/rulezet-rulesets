rule MAL_HuntersInternational_ransomnote {
    meta:
        description = "Matches strings found in Hunters International ransom notes."
        last_modified = "2024-03-31"
        author = "@petermstewart"
        DaysofYara = "91/100"

    strings:
        $a1 = "_   _ _   _ _   _ _____ _____ ____  ____"
        $a2 = "| | | | | | | \\ | |_   _| ____|  _ \\/ ___|"
        $a3 = "| |_| | | | |  \\| | | | |  _| | |_) \\___ \\"
        $a4 = "|  _  | |_| | |\\  | | | | |___|  _ < ___) |"
        $a5 = "|_|_|_|\\___/|_|_\\_|_|_|_|_____|_|_\\_\\____/____ ___ ___  _   _    _    _"
        $a6 = "|_ _| \\ | |_   _| ____|  _ \\| \\ | |  / \\|_   _|_ _/ _ \\| \\ | |  / \\  | |"
        $a7 = "| ||  \\| | | | |  _| | |_) |  \\| | / _ \\ | |  | | | | |  \\| | / _ \\ | |"
        $a8 = "| || |\\  | | | | |___|  _ <| |\\  |/ ___ \\| |  | | |_| | |\\  |/ ___ \\| |___"
        $a9 = "|___|_| \\_| |_| |_____|_| \\_\\_| \\_/_/   \\_\\_| |___\\___/|_| \\_/_/   \\_\\_____|"
        $b1 = "hunters33mmcwww7ek7q5ndahul6nmzmrsumfs6aenicbqon6mxfiqyd.onion"
        $b2 = "hunters33dootzzwybhxyh6xnmumopeoza6u4hkontdqu7awnhmix7ad.onion"
        $b3 = "hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion"
        $b4 = "hunters55atbdusuladzv7vzv6a423bkh6ksl2uftwrxyuarbzlfh7yd.onion"

    condition:
        filesize < 5KB and
        all of ($a*) and
        1 of ($b*)
}