rule TTP_XOR_QUAD_CurrentVersionRun_db12 {
  strings:
    $key_db12 = { 88 7d [2] ac 73 [2] 87 5f [2] a9 7d [2] bd 66 [2] b2 7c [2] ac 61 [2] ae 60 [2] b5 66 [2] a9 61 [2] b5 4e }

  condition:
    any of them
}