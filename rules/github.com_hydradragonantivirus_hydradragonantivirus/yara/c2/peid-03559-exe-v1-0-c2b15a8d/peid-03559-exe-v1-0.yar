rule PEiD_03559_____EXE___________v1_0_________ {
  meta:
    description = "Packer convert base64 to ascii wr3DjMOWw7dFWEXDjsOEwrzDvsOAwqbCsMOzw4bDtyB2MS4wIC0+IMK9w4zDlsO3"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 08 4B 40 00 68 36 3A 40 00 64 A1 }

  condition:
    $a
}