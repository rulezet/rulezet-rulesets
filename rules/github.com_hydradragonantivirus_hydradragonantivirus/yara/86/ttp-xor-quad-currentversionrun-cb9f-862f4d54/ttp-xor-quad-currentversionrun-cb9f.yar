rule TTP_XOR_QUAD_CurrentVersionRun_cb9f {
  strings:
    $key_cb9f = { 98 f0 [2] bc fe [2] 97 d2 [2] b9 f0 [2] ad eb [2] a2 f1 [2] bc ec [2] be ed [2] a5 eb [2] b9 ec [2] a5 c3 }

  condition:
    any of them
}