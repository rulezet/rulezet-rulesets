rule TTP_XOR_QUAD_CurrentVersionRun_de16 {
  strings:
    $key_de16 = { 8d 79 [2] a9 77 [2] 82 5b [2] ac 79 [2] b8 62 [2] b7 78 [2] a9 65 [2] ab 64 [2] b0 62 [2] ac 65 [2] b0 4a }

  condition:
    any of them
}