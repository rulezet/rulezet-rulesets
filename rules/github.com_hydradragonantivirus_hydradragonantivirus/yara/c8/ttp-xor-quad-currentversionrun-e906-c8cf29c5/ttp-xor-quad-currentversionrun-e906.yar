rule TTP_XOR_QUAD_CurrentVersionRun_e906 {
  strings:
    $key_e906 = { ba 69 [2] 9e 67 [2] b5 4b [2] 9b 69 [2] 8f 72 [2] 80 68 [2] 9e 75 [2] 9c 74 [2] 87 72 [2] 9b 75 [2] 87 5a }

  condition:
    any of them
}