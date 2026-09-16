rule ntdll_stackpushdoublenull {
  strings:
    $ntdll_stackpushdoublenull = "hl\x00\x00hntdl" nocase ascii wide

  condition:
    all of them
}