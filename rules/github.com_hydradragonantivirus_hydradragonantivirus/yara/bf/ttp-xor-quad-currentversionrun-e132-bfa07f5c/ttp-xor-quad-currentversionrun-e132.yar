rule TTP_XOR_QUAD_CurrentVersionRun_e132 {
  strings:
    $key_e132 = { b2 5d [2] 96 53 [2] bd 7f [2] 93 5d [2] 87 46 [2] 88 5c [2] 96 41 [2] 94 40 [2] 8f 46 [2] 93 41 [2] 8f 6e }

  condition:
    any of them
}