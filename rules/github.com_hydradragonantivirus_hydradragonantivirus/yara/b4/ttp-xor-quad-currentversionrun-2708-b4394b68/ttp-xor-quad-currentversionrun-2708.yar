rule TTP_XOR_QUAD_CurrentVersionRun_2708 {
  strings:
    $key_2708 = { 74 67 [2] 50 69 [2] 7b 45 [2] 55 67 [2] 41 7c [2] 4e 66 [2] 50 7b [2] 52 7a [2] 49 7c [2] 55 7b [2] 49 54 }

  condition:
    any of them
}