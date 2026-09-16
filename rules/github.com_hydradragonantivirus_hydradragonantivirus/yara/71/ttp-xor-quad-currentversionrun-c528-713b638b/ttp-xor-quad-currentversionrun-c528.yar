rule TTP_XOR_QUAD_CurrentVersionRun_c528 {
  strings:
    $key_c528 = { 96 47 [2] b2 49 [2] 99 65 [2] b7 47 [2] a3 5c [2] ac 46 [2] b2 5b [2] b0 5a [2] ab 5c [2] b7 5b [2] ab 74 }

  condition:
    any of them
}