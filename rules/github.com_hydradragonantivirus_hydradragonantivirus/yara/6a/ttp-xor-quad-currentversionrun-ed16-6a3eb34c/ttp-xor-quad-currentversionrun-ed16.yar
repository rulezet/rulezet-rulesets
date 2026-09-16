rule TTP_XOR_QUAD_CurrentVersionRun_ed16 {
  strings:
    $key_ed16 = { be 79 [2] 9a 77 [2] b1 5b [2] 9f 79 [2] 8b 62 [2] 84 78 [2] 9a 65 [2] 98 64 [2] 83 62 [2] 9f 65 [2] 83 4a }

  condition:
    any of them
}