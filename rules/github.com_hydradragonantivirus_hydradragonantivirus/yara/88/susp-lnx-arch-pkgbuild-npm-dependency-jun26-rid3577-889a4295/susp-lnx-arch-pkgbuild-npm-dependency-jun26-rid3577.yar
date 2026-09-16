rule SUSP_LNX_ARCH_PKGBUILD_NPM_Dependency_Jun26_RID3577: DEMO LINUX SCRIPT SUSP {
  meta:
    description = "Detects suspicious PKGBUILD with NPM dependency and install script"
    author      = "Marius Benthin"
    reference   = "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency"
    date        = "2026-06-15 16:14:21"
    score       = 60
    customer    = "demo"
    license     = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"

    tags         = "DEMO, LINUX, SCRIPT, SUSP"
    minimum_yara = "3.5.0"

  strings:
    $sa1 = { (0A | 20) 64 65 70 65 6E 64 73 3D 28 [0-15] (6E 70 6D | 62 75 6E) }
    $sb1 = { 69 6E 73 74 61 6C 6C 20 2D 44 6D 36 34 34 20 (22 | 27) [0-100] 2E 68 6F 6F 6B (22 | 27) 0A }
    $sb2 = { 69 6E 73 74 61 6C 6C 3D [1-50] 2E 69 6E 73 74 61 6C 6C }

  condition:
    filesize < 100KB and $sa1 and 1 of ($sb*)
}