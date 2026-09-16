rule TTP_XOR_QUAD_CurrentVersionRun_55fc {
  strings:
    $key_55fc = { 06 93 [2] 22 9d [2] 09 b1 [2] 27 93 [2] 33 88 [2] 3c 92 [2] 22 8f [2] 20 8e [2] 3b 88 [2] 27 8f [2] 3b a0 }

  condition:
    any of them
}