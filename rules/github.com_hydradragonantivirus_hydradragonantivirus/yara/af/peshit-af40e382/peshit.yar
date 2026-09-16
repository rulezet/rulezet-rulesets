rule peshit {
  meta:
    author      = "PEiD"
    description = "UPXShit 0.05 -> snaker"
    group       = "158"
    function    = "0"

  strings:
    $a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 ?? 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF }

  condition:
    $a0
}