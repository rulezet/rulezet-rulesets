rule TTP_XOR_QUAD_CurrentVersionRun_e29f {
  strings:
    $key_e29f = { b1 f0 [2] 95 fe [2] be d2 [2] 90 f0 [2] 84 eb [2] 8b f1 [2] 95 ec [2] 97 ed [2] 8c eb [2] 90 ec [2] 8c c3 }

  condition:
    any of them
}