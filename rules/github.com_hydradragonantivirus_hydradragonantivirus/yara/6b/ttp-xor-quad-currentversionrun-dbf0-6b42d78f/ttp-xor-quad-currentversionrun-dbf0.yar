rule TTP_XOR_QUAD_CurrentVersionRun_dbf0 {
  strings:
    $key_dbf0 = { 88 9f [2] ac 91 [2] 87 bd [2] a9 9f [2] bd 84 [2] b2 9e [2] ac 83 [2] ae 82 [2] b5 84 [2] a9 83 [2] b5 ac }

  condition:
    any of them
}