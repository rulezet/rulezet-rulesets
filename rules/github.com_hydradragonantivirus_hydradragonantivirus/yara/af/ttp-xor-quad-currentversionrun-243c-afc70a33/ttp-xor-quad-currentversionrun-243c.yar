rule TTP_XOR_QUAD_CurrentVersionRun_243c {
  strings:
    $key_243c = { 77 53 [2] 53 5d [2] 78 71 [2] 56 53 [2] 42 48 [2] 4d 52 [2] 53 4f [2] 51 4e [2] 4a 48 [2] 56 4f [2] 4a 60 }

  condition:
    any of them
}