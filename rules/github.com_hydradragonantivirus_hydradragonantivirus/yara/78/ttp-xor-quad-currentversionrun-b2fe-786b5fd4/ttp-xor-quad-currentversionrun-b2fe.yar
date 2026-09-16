rule TTP_XOR_QUAD_CurrentVersionRun_b2fe {
  strings:
    $key_b2fe = { e1 91 [2] c5 9f [2] ee b3 [2] c0 91 [2] d4 8a [2] db 90 [2] c5 8d [2] c7 8c [2] dc 8a [2] c0 8d [2] dc a2 }

  condition:
    any of them
}