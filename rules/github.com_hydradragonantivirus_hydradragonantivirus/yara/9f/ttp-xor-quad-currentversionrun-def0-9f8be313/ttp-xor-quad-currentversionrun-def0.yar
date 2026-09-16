rule TTP_XOR_QUAD_CurrentVersionRun_def0 {
  strings:
    $key_def0 = { 8d 9f [2] a9 91 [2] 82 bd [2] ac 9f [2] b8 84 [2] b7 9e [2] a9 83 [2] ab 82 [2] b0 84 [2] ac 83 [2] b0 ac }

  condition:
    any of them
}