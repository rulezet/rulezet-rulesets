rule TTP_XOR_QUAD_CurrentVersionRun_e1fe {
  strings:
    $key_e1fe = { b2 91 [2] 96 9f [2] bd b3 [2] 93 91 [2] 87 8a [2] 88 90 [2] 96 8d [2] 94 8c [2] 8f 8a [2] 93 8d [2] 8f a2 }

  condition:
    any of them
}