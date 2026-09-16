rule irc
{
    meta:
    description = "Indicates use of IRC"
    
    strings:
    $irc0 = "join" nocase fullword
    $irc1 = "msg" nocase fullword
    $irc2 = "nick" nocase fullword
    $irc3 = "notice" nocase fullword
    $irc4 = "part" nocase fullword
    $irc5 = "ping" nocase fullword
    $irc6 = "quit" nocase fullword
    $irc7 = "chat" nocase fullword
    $irc8 = "privmsg" nocase fullword
    
    condition:
    4 of ($irc*)
}