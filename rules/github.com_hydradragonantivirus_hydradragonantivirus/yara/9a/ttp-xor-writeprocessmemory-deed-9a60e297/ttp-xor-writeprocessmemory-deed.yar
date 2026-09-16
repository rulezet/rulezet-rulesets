rule TTP_XOR_WriteProcessMemory_deed {
  strings:
    $key_deed = { 89 9f [2] bb bd [2] bd 88 [2] 93 88 [2] ac 94 }

  condition:
    any of them
}