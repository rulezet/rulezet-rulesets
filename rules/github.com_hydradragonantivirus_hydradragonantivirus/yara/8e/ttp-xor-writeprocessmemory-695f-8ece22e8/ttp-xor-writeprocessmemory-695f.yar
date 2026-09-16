rule TTP_XOR_WriteProcessMemory_695f {
  strings:
    $key_695f = { 3e 2d [2] 0c 0f [2] 0a 3a [2] 24 3a [2] 1b 26 }

  condition:
    any of them
}