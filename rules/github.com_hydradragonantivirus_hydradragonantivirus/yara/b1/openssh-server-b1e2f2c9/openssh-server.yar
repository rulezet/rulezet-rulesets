rule openssh_server {
  meta:
    description   = "Detection patterns for the tool 'openssh server' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "openssh server"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1 = /Add\-WindowsCapability\s\-Online\s\-Name\sOpenSSH\.Server/ nocase ascii wide

  condition:
    any of them
}