rule TTP_XOR_QUAD_CurrentVersionRun_f338 {
  strings:
    $key_f338 = { a0 57 [2] 84 59 [2] af 75 [2] 81 57 [2] 95 4c [2] 9a 56 [2] 84 4b [2] 86 4a [2] 9d 4c [2] 81 4b [2] 9d 64 }

  condition:
    any of them
}