import "pe"
rule _ACProtect_13x__14x_DLL__Risco_Software_Inc_ {
  meta:
    description = "ACProtect 1.3x - 1.4x DLL -> Risco Software Inc."

  strings:
    $0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 ?? BA ?? ?? CD 21 B8 ?? ?? CD 21 }
    $1 = { 80 7C 24 08 01 0F 85 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}