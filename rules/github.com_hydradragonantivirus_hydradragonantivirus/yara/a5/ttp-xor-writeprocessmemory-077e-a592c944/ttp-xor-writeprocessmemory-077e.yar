rule TTP_XOR_WriteProcessMemory_077e {
  strings:
    $key_077e = { 50 0c [2] 62 2e [2] 64 1b [2] 4a 1b [2] 75 07 }

  condition:
    any of them
}