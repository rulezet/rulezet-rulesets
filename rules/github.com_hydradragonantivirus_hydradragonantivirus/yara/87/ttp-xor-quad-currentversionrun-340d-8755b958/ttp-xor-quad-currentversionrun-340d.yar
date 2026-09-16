rule TTP_XOR_QUAD_CurrentVersionRun_340d {
  strings:
    $key_340d = { 67 62 [2] 43 6c [2] 68 40 [2] 46 62 [2] 52 79 [2] 5d 63 [2] 43 7e [2] 41 7f [2] 5a 79 [2] 46 7e [2] 5a 51 }

  condition:
    any of them
}